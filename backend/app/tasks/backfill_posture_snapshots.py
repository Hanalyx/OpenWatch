"""
Backfill Posture Snapshots from Historical Scan Data

One-time script to populate posture_snapshots table from existing scan history.
This enables the Compliance Trends chart to show historical data.

Usage:
    # Via Celery task
    docker exec openwatch-worker celery -A app.celery_app call backfill_posture_snapshots

    # Or run directly
    docker exec openwatch-backend python -c "from app.tasks.backfill_posture_snapshots import backfill_posture_snapshots; backfill_posture_snapshots()"
"""

import logging
from datetime import datetime, time, timezone
from typing import Any, Dict

from celery import shared_task
from sqlalchemy import text

from app.database import PostureSnapshot, SessionLocal

logger = logging.getLogger(__name__)


@shared_task(name="backfill_posture_snapshots")
def backfill_posture_snapshots(days_back: int = 90) -> Dict[str, Any]:
    """
    Backfill posture snapshots from historical scan data.

    For each day with completed scans, creates posture snapshots using
    the latest scan result for each host on that day.

    Args:
        days_back: Number of days to look back (default: 90)

    Returns:
        Summary of backfill results
    """
    logger.info(f"Starting posture snapshot backfill for last {days_back} days")

    db = SessionLocal()
    try:
        # Find all dates with completed scans (excluding today - today's snapshot created by daily task)
        dates_query = text(
            """
            SELECT DISTINCT DATE(completed_at) as scan_date
            FROM scans
            WHERE status = 'completed'
              AND completed_at IS NOT NULL
              AND DATE(completed_at) < CURRENT_DATE
              AND completed_at >= CURRENT_DATE - INTERVAL ':days days'
            ORDER BY scan_date ASC
        """.replace(
                ":days", str(days_back)
            )
        )

        dates_result = db.execute(dates_query).fetchall()
        scan_dates = [row.scan_date for row in dates_result]

        logger.info(f"Found {len(scan_dates)} dates with historical scan data")

        total_created = 0
        total_skipped = 0
        total_errors = 0
        dates_processed = 0

        for scan_date in scan_dates:
            try:
                created, skipped = _create_snapshots_for_date(db, scan_date)
                total_created += created
                total_skipped += skipped
                dates_processed += 1

                if dates_processed % 10 == 0:
                    logger.info(f"Progress: {dates_processed}/{len(scan_dates)} dates processed")

            except Exception as e:
                logger.exception(f"Error processing date {scan_date}: {e}")
                total_errors += 1

        logger.info(
            f"Backfill complete: {total_created} snapshots created, "
            f"{total_skipped} skipped, {total_errors} errors across {dates_processed} dates"
        )

        return {
            "success": True,
            "dates_processed": dates_processed,
            "snapshots_created": total_created,
            "snapshots_skipped": total_skipped,
            "errors": total_errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.exception(f"Backfill failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


def _create_snapshots_for_date(db, scan_date) -> tuple[int, int]:
    """
    Create posture snapshots for all hosts that had scans on a specific date.

    Uses the latest completed scan for each host on that date.

    Args:
        db: Database session
        scan_date: Date to create snapshots for

    Returns:
        Tuple of (created_count, skipped_count)
    """
    # Get latest scan result for each host on this date
    query = text(
        """
        WITH latest_scans AS (
            SELECT DISTINCT ON (s.host_id)
                s.host_id,
                s.id as scan_id,
                s.completed_at,
                sr.total_rules,
                sr.passed_rules,
                sr.failed_rules,
                sr.error_rules,
                sr.not_applicable_rules,
                sr.severity_critical_passed,
                sr.severity_critical_failed,
                sr.severity_high_passed,
                sr.severity_high_failed,
                sr.severity_medium_passed,
                sr.severity_medium_failed,
                sr.severity_low_passed,
                sr.severity_low_failed
            FROM scans s
            JOIN scan_results sr ON s.id = sr.scan_id
            WHERE s.status = 'completed'
              AND DATE(s.completed_at) = :scan_date
            ORDER BY s.host_id, s.completed_at DESC
        )
        SELECT * FROM latest_scans
    """
    )

    results = db.execute(query, {"scan_date": scan_date}).fetchall()

    created = 0
    skipped = 0

    for row in results:
        # Check if snapshot already exists for this host and date
        existing = db.execute(
            text(
                """
                SELECT id FROM posture_snapshots
                WHERE host_id = :host_id AND DATE(snapshot_date) = :scan_date
            """
            ),
            {"host_id": row.host_id, "scan_date": scan_date},
        ).fetchone()

        if existing:
            skipped += 1
            continue

        # Calculate compliance score
        total_rules = row.total_rules or 0
        passed_rules = row.passed_rules or 0
        compliance_score = (passed_rules / total_rules * 100) if total_rules > 0 else 0.0

        # Create snapshot at end of day for historical dates
        snapshot_datetime = datetime.combine(scan_date, time(23, 59, 59))

        snapshot = PostureSnapshot(
            host_id=row.host_id,
            snapshot_date=snapshot_datetime,
            total_rules=total_rules,
            passed=passed_rules,
            failed=row.failed_rules or 0,
            error_count=row.error_rules or 0,
            not_applicable=row.not_applicable_rules or 0,
            compliance_score=round(compliance_score, 2),
            severity_critical_passed=row.severity_critical_passed or 0,
            severity_critical_failed=row.severity_critical_failed or 0,
            severity_high_passed=row.severity_high_passed or 0,
            severity_high_failed=row.severity_high_failed or 0,
            severity_medium_passed=row.severity_medium_passed or 0,
            severity_medium_failed=row.severity_medium_failed or 0,
            severity_low_passed=row.severity_low_passed or 0,
            severity_low_failed=row.severity_low_failed or 0,
            rule_states={},
            source_scan_id=row.scan_id,
        )

        db.add(snapshot)
        created += 1

    db.commit()

    logger.debug(f"Date {scan_date}: {created} created, {skipped} skipped")

    return created, skipped


__all__ = ["backfill_posture_snapshots"]
