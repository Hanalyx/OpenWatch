"""
Backfill Posture Snapshot Rule States

One-time Celery task to populate rule_states JSONB on existing posture_snapshots
that have empty rule_states ({}). Queries scan_findings via source_scan_id and
builds rule_states with actual values from evidence.

Usage:
    # Via Celery task
    docker exec openwatch-worker celery -A app.celery_app call backfill_snapshot_rule_states

    # Or run directly
    docker exec openwatch-backend python -c \
        "from app.tasks.backfill_snapshot_rule_states import backfill_snapshot_rule_states; \
        backfill_snapshot_rule_states()"
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from celery import shared_task
from sqlalchemy import text

from app.database import SessionLocal

logger = logging.getLogger(__name__)

BATCH_SIZE = 50


def _extract_actual(evidence: Any) -> Any:
    """Extract actual value from evidence JSONB."""
    if not evidence:
        return None

    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (json.JSONDecodeError, TypeError):
            return None

    if not isinstance(evidence, list):
        return None

    actuals = []
    for item in evidence:
        if isinstance(item, dict) and item.get("actual") is not None:
            actuals.append(str(item["actual"]))

    if not actuals:
        return None
    if len(actuals) == 1:
        return actuals[0]
    return actuals


def _build_rule_states_for_scan(db: Any, scan_id: str) -> Dict[str, Any]:
    """Build rule_states dict from scan_findings for a given scan."""
    result = db.execute(
        text(
            """
            SELECT rule_id, title, severity, status,
                   framework_section, evidence
            FROM scan_findings
            WHERE scan_id = :scan_id
            """
        ),
        {"scan_id": scan_id},
    )
    findings = result.fetchall()

    rule_states: Dict[str, Any] = {}
    for f in findings:
        actual = _extract_actual(f.evidence)
        state: Dict[str, Any] = {
            "status": f.status,
            "severity": f.severity,
            "title": f.title,
        }
        if f.framework_section:
            state["category"] = f.framework_section
        if actual is not None:
            state["actual"] = actual
        rule_states[f.rule_id] = state

    return rule_states


@shared_task(name="backfill_snapshot_rule_states")
def backfill_snapshot_rule_states() -> Dict[str, Any]:
    """
    Backfill rule_states on posture_snapshots that have empty rule_states.

    For each snapshot with rule_states = '{}', queries scan_findings via
    source_scan_id and populates rule_states with status, severity, title,
    category, and actual values from evidence.

    Returns:
        Summary of backfill results.
    """
    logger.info("Starting snapshot rule_states backfill")

    db = SessionLocal()
    try:
        # Find snapshots with empty rule_states that have a source_scan_id
        empty_snapshots = db.execute(
            text(
                """
                SELECT id, source_scan_id
                FROM posture_snapshots
                WHERE (rule_states::text = '{}' OR rule_states IS NULL)
                  AND source_scan_id IS NOT NULL
                ORDER BY snapshot_date ASC
                """
            )
        ).fetchall()

        total = len(empty_snapshots)
        logger.info("Found %d snapshots to backfill", total)

        updated = 0
        skipped = 0
        errors = 0

        for i, snapshot in enumerate(empty_snapshots):
            try:
                rule_states = _build_rule_states_for_scan(db, str(snapshot.source_scan_id))

                if not rule_states:
                    skipped += 1
                    continue

                db.execute(
                    text(
                        """
                        UPDATE posture_snapshots
                        SET rule_states = :rule_states
                        WHERE id = :id
                        """
                    ),
                    {
                        "rule_states": json.dumps(rule_states),
                        "id": str(snapshot.id),
                    },
                )
                updated += 1

                # Commit in batches
                if (i + 1) % BATCH_SIZE == 0:
                    db.commit()
                    logger.info(
                        "Progress: %d/%d snapshots processed (%d updated)",
                        i + 1,
                        total,
                        updated,
                    )

            except Exception as e:
                logger.warning("Failed to backfill snapshot %s: %s", snapshot.id, e)
                errors += 1

        # Final commit
        db.commit()

        logger.info(
            "Backfill complete: %d updated, %d skipped, %d errors out of %d",
            updated,
            skipped,
            errors,
            total,
        )

        return {
            "success": True,
            "total_snapshots": total,
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.exception("Backfill failed: %s", e)
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        db.close()


__all__ = ["backfill_snapshot_rule_states"]
